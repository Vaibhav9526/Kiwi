/** Mail-flow + audit repositories — SQLite implementations. */
import type { Db } from "./interfaces.js";
import type { MailflowRepository, AuditRepository } from "./interfaces.js";
import type { MailflowEvent, MailflowIngest, MailDirection, PolicyVerdict } from "../mailflow/model.js";
import type { AuditEventInput, AuditRecord } from "../audit/model.js";
import type { SqlParam } from "./interfaces.js";

interface MailflowRow {
  id: string;
  org_id: string | null;
  direction: MailDirection;
  sender: string;
  recipient: string;
  ts: number;
  message_id: string | null;
  tls_version: string | null;
  security_status: string;
  policy_verdict: PolicyVerdict;
  received_at: number;
}

export class SqliteMailflowRepository implements MailflowRepository {
  constructor(private readonly db: Db) {}

  ingest(event: MailflowIngest): { id: string } {
    this.db.run(
      `INSERT INTO mailflow_events
       (id, org_id, direction, sender, recipient, ts, message_id, tls_version, security_status, policy_verdict, received_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      event.id,
      event.orgId,
      event.direction,
      event.sender,
      event.recipient,
      event.ts,
      event.messageId,
      event.tlsVersion,
      event.securityStatus,
      event.policyVerdict,
      Date.now(),
    );
    return { id: event.id };
  }

  query(filter: { orgId?: string | null; recipientDomain?: string; sinceTs?: number; untilTs?: number; limit: number }): MailflowEvent[] {
    const clauses: string[] = [];
    const params: SqlParam[] = [];
    if (filter.orgId) {
      clauses.push("org_id = ?");
      params.push(filter.orgId);
    }
    if (filter.recipientDomain) {
      clauses.push("recipient LIKE ?");
      params.push(`%@${filter.recipientDomain}`);
    }
    if (typeof filter.sinceTs === "number") {
      clauses.push("ts >= ?");
      params.push(filter.sinceTs);
    }
    if (typeof filter.untilTs === "number") {
      clauses.push("ts <= ?");
      params.push(filter.untilTs);
    }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
    params.push(Math.min(filter.limit, 1000));
    const rows = this.db.all(
      `SELECT id, org_id, direction, sender, recipient, ts, message_id, tls_version, security_status, policy_verdict, received_at
       FROM mailflow_events ${where} ORDER BY ts DESC, id DESC LIMIT ?`,
      ...params,
    ) as MailflowRow[];
    return rows.map((r) => ({
      id: r.id,
      org_id: r.org_id,
      direction: r.direction,
      sender: r.sender,
      recipient: r.recipient,
      ts: r.ts,
      message_id: r.message_id,
      tls_version: r.tls_version,
      security_status: r.security_status,
      policy_verdict: r.policy_verdict,
      received_at: r.received_at,
    }));
  }
}

export class SqliteAuditRepository implements AuditRepository {
  constructor(private readonly db: Db) {}

  append(input: AuditEventInput, prevHash: string, entryHash: string, seq: number, ts: number): AuditRecord {
    this.db.run(
      `INSERT INTO audit_log
       (seq, ts, actor_subject, actor_roles, org_id, action, resource, outcome, request_id, details, prev_hash, entry_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      seq,
      ts,
      input.actor.subject,
      JSON.stringify(input.actor.roles),
      input.orgId,
      input.action,
      input.resource,
      input.outcome,
      input.requestId,
      JSON.stringify(input.details),
      prevHash,
      entryHash,
    );
    return {
      seq,
      ts,
      actor_subject: input.actor.subject,
      actor_roles: JSON.stringify(input.actor.roles),
      org_id: input.orgId,
      action: input.action,
      resource: input.resource,
      outcome: input.outcome,
      request_id: input.requestId,
      details: JSON.stringify(input.details),
      prev_hash: prevHash,
      entry_hash: entryHash,
    };
  }

  readAt(seq: number): AuditRecord | undefined {
    const row = this.db.one(
      "SELECT seq, ts, actor_subject, actor_roles, org_id, action, resource, outcome, request_id, details, prev_hash, entry_hash FROM audit_log WHERE seq = ?",
      seq,
    ) as AuditRecord | undefined;
    return row ?? undefined;
  }

  last(): AuditRecord | undefined {
    const row = this.db.one(
      "SELECT seq, ts, actor_subject, actor_roles, org_id, action, resource, outcome, request_id, details, prev_hash, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1",
    ) as AuditRecord | undefined;
    return row ?? undefined;
  }

  range(since: number, until: number, limit: number): AuditRecord[] {
    return this.db.all(
      "SELECT seq, ts, actor_subject, actor_roles, org_id, action, resource, outcome, request_id, details, prev_hash, entry_hash FROM audit_log WHERE ts >= ? AND ts <= ? ORDER BY seq ASC LIMIT ?",
      since,
      until,
      limit,
    ) as AuditRecord[];
  }
}
