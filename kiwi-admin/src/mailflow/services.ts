/** Mail-flow and audit services (RBAC-enforced, audited). */
import { randomUUID } from "node:crypto";
import { requirePermission } from "../rbac/rbac.js";
import type { Actor } from "../rbac/rbac.js";
import { parseMailflowIngest } from "./model.js";
import type { MailflowEvent, MailDirection, PolicyVerdict } from "./model.js";
import type { AuditRepository, MailflowRepository } from "../db/interfaces.js";
import type { AuditEventInput, AuditOutcome } from "../audit/model.js";
import { verifyChain } from "../audit/chain.js";
import { buildAuditExport, AUDIT_EXPORT_MAX_ROWS, type AuditExport } from "../audit/export.js";
import { RequestValidationError } from "../util/validate.js";
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

  async ingest(actor: Actor, raw: ExternalMailflowInput): Promise<{ id: string }> {
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

  async query(
    actor: Actor,
    filter: { orgId?: string; recipientDomain?: string; sinceTs?: number; untilTs?: number; limit: number },
  ): Promise<{ items: MailflowEvent[] }> {
    // Org-defaulted reads (T-193/H4): an org-bound caller without an
    // explicit filter reads their OWN org, never all orgs. Only an
    // org-unbound (platform) caller with no filter reads globally —
    // that is the platform read, not a default.
    const orgId = filter.orgId ?? actor.orgId ?? null;
    requirePermission(actor, "mailflow.read", orgId);
    const bounded = {
      ...filter,
      ...(orgId === null ? {} : { orgId }),
      limit: Math.min(Math.max(filter.limit ?? 50, 1), 1000),
    };
    return { items: await this.repos.mailflow.query(bounded) };
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

/**
 * The audit log and its access paths.
 *
 * Note on self-auditing: `query` and `verify` gate on `audit.read` but do NOT
 * record their own denials, and `export` records only its successes. The audit
 * service is the thing that writes the chain, so having it audit its refusals
 * would make every denial of a log read recurse into the log it was refused.
 * Mutations made through the other services are audited normally by
 * `ServiceContainer.auditWrap`.
 */
export class AuditService {
  constructor(private readonly repos: { audit: AuditRepository }) {}
  /**
   * In-process append serialization (T-193/H6, defense in depth): the
   * repository's `appendChained` is already atomic inside its own
   * transaction (including across processes on Postgres), so this gate only
   * spares the database lock under bursts from this process. The chain is
   * failure-atomic per append — a rejected append never advances the gate.
   */
  private appendGate: Promise<unknown> = Promise.resolve();

  async append(input: AuditEventInput, ts: number): Promise<{ seq: number; entry_hash: string }> {
    const run = this.appendGate.then(() => this.appendInner(input, ts));
    // The gate always advances, even when an append rejects — a failure
    // must not wedge every later append behind it.
    this.appendGate = run.catch(() => undefined);
    return run;
  }

  private async appendInner(input: AuditEventInput, ts: number): Promise<{ seq: number; entry_hash: string }> {
    // No client max+1 here (T-193/H6): tail-read, seq assignment, hash, and
    // insert happen inside the repository transaction. A previous revision
    // read `last()` here and inserted a precomputed `seq`, which two
    // processes could compute identically and collide on the primary key.
    const rec = await this.repos.audit.appendChained(input, ts);
    return { seq: rec.seq, entry_hash: rec.entry_hash };
  }

  /**
   * Read audit history. Requires `audit.read` (SECURITY.md rule 11: the audit
   * log is a security control, so reading it is a permission, not a given).
   * `filter.orgId` narrows to one org and is applied in SQL — an absent orgId
   * means the whole log, which is what the org-agnostic read is for.
   */
  async query(actor: Actor, filter: AuditQueryFilter): Promise<AuditQueryRow[]> {
    // Same org-default rule as mailflow reads (T-193/H4).
    const orgId = filter.orgId ?? actor.orgId ?? null;
    requirePermission(actor, "audit.read", orgId);
    const bounded = Math.min(Math.max(filter.limit, 1), 1000);
    const rows = await this.repos.audit.range(
      filter.since ?? 0,
      filter.until ?? Number.MAX_SAFE_INTEGER,
      bounded,
      orgId,
    );
    return rows.map((r) => ({
      seq: r.seq,
      ts: r.ts,
      actor_subject: r.actor_subject,
      action: r.action,
      outcome: r.outcome,
      details: r.details,
    }));
  }

  /**
   * Verify the whole hash chain. Also `audit.read`: the result describes the
   * integrity of the entire log, so it is no less sensitive than reading it.
   *
   * Always reads EVERY row, never an org-scoped slice — a hash chain only
   * validates over the full sequence, and a filtered window would report a
   * false "valid" for a log whose other rows were tampered with.
   *
   * Shares `verifyChain` with the T-179 export so the two cannot disagree.
   */
  async verify(actor: Actor, opts: { limit: number }): Promise<{ valid: boolean; checked: number; error: string | null }> {
    requirePermission(actor, "audit.read", null);
    // Honest attestation (T-193/H8): limit 0 (or negative) would verify an
    // empty window and report `valid: true` — attesting nothing. Refuse
    // instead of attesting; callers that want the whole chain pass a large
    // limit or none at all.
    if (!Number.isSafeInteger(opts.limit) || opts.limit < 1) {
      throw new RequestValidationError("limit", "must be an integer >= 1");
    }
    const rows = await this.repos.audit.range(0, Number.MAX_SAFE_INTEGER, Math.min(opts.limit, AUDIT_EXPORT_MAX_ROWS));
    const state = verifyChain(rows);
    return { valid: state.valid, checked: state.checked, error: state.error };
  }

  /**
   * T-179: signed NDJSON export of the audit chain. Requires `audit.export`,
   * which only org_admin holds — every role may READ the log, but taking a
   * signed copy of the whole chain off-box is an owner-level act.
   *
   * There is deliberately no caller-supplied window. A truncated export would
   * still report `chain_state.valid: true` (a prefix of a valid chain is
   * itself valid), so a paged export would be indistinguishable from a
   * complete one. The export is all-or-nothing; the cap below is a memory
   * safety valve that REFUSES rather than truncating.
   */
  async export(actor: Actor, opts: { now: number; key: string | null }): Promise<AuditExport> {
    requirePermission(actor, "audit.export", null);
    // Fetch one past the cap: a full batch means the chain is longer than we
    // are willing to buffer, which is knowable only by asking for the extra row.
    const rows = await this.repos.audit.range(0, Number.MAX_SAFE_INTEGER, AUDIT_EXPORT_MAX_ROWS + 1);
    if (rows.length > AUDIT_EXPORT_MAX_ROWS) {
      throw new RequestValidationError(
        "audit",
        `export is capped at ${AUDIT_EXPORT_MAX_ROWS} rows and the chain is longer; ` +
          "archive and prune the log before exporting",
      );
    }
    const result = buildAuditExport(rows, { now: opts.now, key: opts.key });
    // Take a signed copy of the whole log off-box is exactly the kind of act
    // that must leave a trace, so unlike a plain read this one is recorded —
    // otherwise the log could be exfiltrated with nothing to show for it. The
    // row is appended AFTER the snapshot, so the export covers the chain as it
    // was just before its own record. Denials are not self-audited, matching
    // query/verify (see the note on AuditService).
    // Unit note (T-193/M2): the row uses the same clock source as every other
    // audit row (wall-clock milliseconds); `opts.now` is reserved for the
    // export's `exported_at` header, where a caller-supplied deterministic
    // timestamp actually belongs.
    await this.append(
      {
        actor: { subject: actor.subject, roles: actor.roles },
        orgId: null,
        action: "audit.export",
        resource: null,
        outcome: "allowed",
        requestId: null,
        // The key FINGERPRINT only — never the key (see audit/export.ts).
        details: { rows: result.rows, signed: result.signature.signed, key_id: result.signature.key_id },
      },
      Date.now(),
    );
    return result;
  }
}
