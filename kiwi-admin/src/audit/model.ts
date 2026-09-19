/** Audit event model — schema per docs/contracts/admin-api.md §7. */
import { assertNonEmptyString, assertIdentifier } from "../util/validate.js";
import { RequestValidationError, isRecord } from "../util/validate.js";
import type { OrgRole } from "../types.js";

export type AuditOutcome = "allowed" | "denied" | "error";

export interface AuditActor {
  subject: string;
  roles: OrgRole[];
}

export interface AuditEventInput {
  actor: AuditActor;
  orgId: string | null;
  action: string;
  resource: string | null;
  outcome: AuditOutcome;
  requestId: string | null;
  details: Record<string, unknown>;
}

/** Serialized audit record as persisted/read (canonical hash input = JSON of these fields). */
export interface AuditRecord {
  seq: number;
  ts: number;
  actor_subject: string | null;
  actor_roles: string | null;
  org_id: string | null;
  action: string;
  resource: string | null;
  outcome: AuditOutcome;
  request_id: string | null;
  details: string | null;
  prev_hash: string;
  entry_hash: string;
}

/** Canonicalize and validate an untrusted audit input. */
export function parseAuditEventInput(raw: unknown): AuditEventInput {
  if (!isRecord(raw)) throw new RequestValidationError("event", "expected object");
  const action = assertNonEmptyString(raw["action"], "action", 128);
  let actorSubject = "anonymous";
  let roles: OrgRole[] = [];
  const actorRaw = raw["actor"];
  if (isRecord(actorRaw)) {
    actorSubject = assertIdentifier(actorRaw["subject"] ?? "anonymous", "actor.subject");
    const rawRoles = actorRaw["roles"];
    if (Array.isArray(rawRoles)) {
      roles = rawRoles.filter(
        (r): r is OrgRole => r === "org_admin" || r === "security_admin" || r === "viewer",
      );
    }
  }
  const orgId = raw["org_id"] === undefined || raw["org_id"] === null ? null : assertIdentifier(raw["org_id"], "org_id");
  const resource =
    raw["resource"] === undefined || raw["resource"] === null ? null : assertNonEmptyString(raw["resource"], "resource", 256);
  const outcomeRaw = raw["outcome"];
  const outcome: AuditOutcome = outcomeRaw === "allowed" || outcomeRaw === "denied" || outcomeRaw === "error" ? outcomeRaw : "allowed";
  const requestId =
    raw["request_id"] === undefined || raw["request_id"] === null ? null : assertNonEmptyString(raw["request_id"], "request_id", 256);
  let details: Record<string, unknown> = {};
  const rawDetails = raw["details"];
  if (rawDetails !== undefined && rawDetails !== null) {
    if (!isRecord(rawDetails)) throw new RequestValidationError("details", "expected object");
    details = rawDetails;
  }
  return { actor: { subject: actorSubject, roles }, orgId, action, resource, outcome, requestId, details };
}

/** Canonical audit row key: '<seq> | <ts> | <actor_subject> | <action> | <outcome>'. */
export function auditRowKey(r: Pick<AuditRecord, "seq" | "ts" | "actor_subject" | "action" | "outcome">): string {
  return `${r.seq} | ${r.ts} | ${r.actor_subject ?? ""} | ${r.action} | ${r.outcome}`;
}
