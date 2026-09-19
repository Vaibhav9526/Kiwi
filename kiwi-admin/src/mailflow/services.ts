/** Mail-flow and audit services (RBAC-enforced, audited). */
import { randomUUID } from "node:crypto";
import { requirePermission } from "../rbac/rbac.js";
import type { Actor } from "../rbac/rbac.js";
import { parseMailflowIngest } from "./model.js";
import type { MailflowEvent, MailDirection, PolicyVerdict } from "./model.js";
import type { AuditRepository, MailflowRepository } from "../db/interfaces.js";
import type { AuditEventInput, AuditOutcome } from "../audit/model.js";
import { canonicalEventJson, computeEntryHash } from "../audit/chain.js";
import type { ServiceContainerLike } from "../policy/services.js";

export interface ExternalMailflowInput {
  direction: MailDirection;
  sender: string;
  recipient: string;
  ts: number;
  message_id: string | null;
  tls_version: string | null;
  security_status: string;
  policy_verdict: PolicyVerdict;
  org_id: string | null;
}

export class MailflowService {
  constructor(
    private readonly repos: { mailflow: MailflowRepository },
    private readonly ctx: ServiceContainerLike,
  ) {}

  ingest(actor: Actor, raw: ExternalMailflowInput): { id: string } {
    return this.ctx.auditWrap(
      actor,
      raw.org_id,
      "mailflow.ingest",
      null,
      () => {
        const parsed = parseMailflowIngest(raw, () => randomUUID());
        return this.repos.mailflow.ingest(parsed);
      },
      "mailflow.ingest",
    );
  }

  query(actor: Actor, filter: { orgId?: string; recipientDomain?: string; sinceTs?: number; untilTs?: number; limit: number }): { items: MailflowEvent[] } {
    requirePermission(actor, "mailflow.read", filter.orgId ?? null);
    const bounded = { ...filter, limit: Math.min(Math.max(filter.limit ?? 50, 1), 1000) };
    return { items: this.repos.mailflow.query(bounded) };
  }
}

export interface AuditQueryFilter {
  orgId?: string;
  since?: number;
  until?: number;
  limit: number;
}

export interface AuditQueryRow {
  seq: number;
  ts: number;
  actor_subject: string | null;
  action: string;
  outcome: string;
  details: string | null;
}

export class AuditService {
  constructor(private readonly repos: { audit: AuditRepository }) {}

  append(input: AuditEventInput, ts: number): { seq: number; entry_hash: string } {
    const last = this.repos.audit.last();
    const prevHash = last?.entry_hash ?? "genesis";
    const seq = (last?.seq ?? 0) + 1;
    const entryHash = computeEntryHash(canonicalEventJson(input), prevHash);
    this.repos.audit.append(input, prevHash, entryHash, seq, ts);
    return { seq, entry_hash: entryHash };
  }

  query(filter: AuditQueryFilter): AuditQueryRow[] {
    const bounded = Math.min(Math.max(filter.limit, 1), 1000);
    const rows = this.repos.audit.range(filter.since ?? 0, filter.until ?? Number.MAX_SAFE_INTEGER, bounded);
    return rows.map((r) => ({
      seq: r.seq,
      ts: r.ts,
      actor_subject: r.actor_subject,
      action: r.action,
      outcome: r.outcome,
      details: r.details,
    }));
  }

  verify(opts: { limit: number }): { valid: boolean; checked: number; error: string | null } {
    const rows = this.repos.audit.range(0, Number.MAX_SAFE_INTEGER, Math.min(opts.limit, 10000));
    let expectedPrev = "genesis";
    let expectedSeq: number | null = null;
    for (const r of rows) {
      // Defense in depth alongside the DB append-only guard (admin-api.md §7):
      // seq values must be contiguous within the verified window, so a gap
      // left by row removal is flagged even if hashes were recomputed.
      if (expectedSeq !== null && r.seq !== expectedSeq) {
        return { valid: false, checked: rows.length, error: `chain non-contiguous: expected seq ${expectedSeq}` };
      }
      expectedSeq = r.seq + 1;
      const eventJson = JSON.stringify({
        actor: { subject: r.actor_subject, roles: JSON.parse(r.actor_roles ?? "[]") as string[] },
        org_id: r.org_id,
        action: r.action,
        resource: r.resource,
        outcome: r.outcome,
        request_id: r.request_id,
        details: JSON.parse(r.details ?? "{}") as Record<string, unknown>,
      });
      const recomputed = computeEntryHash(eventJson, expectedPrev);
      if (r.prev_hash !== expectedPrev || r.entry_hash !== recomputed) {
        return { valid: false, checked: rows.length, error: `chain broken at seq ${r.seq}` };
      }
      expectedPrev = r.entry_hash;
    }
    return { valid: true, checked: rows.length, error: null };
  }
}
