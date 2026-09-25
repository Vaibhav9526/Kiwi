/** Mail-flow and audit services (RBAC-enforced, audited). */
import { randomUUID } from "node:crypto";
import { AuthorizationDeniedError, hasPermission, requirePermission } from "../rbac/rbac.js";
import type { Actor } from "../rbac/rbac.js";
import { parseMailflowIngest } from "./model.js";
import type { MailflowEvent, MailDirection, PolicyVerdict } from "./model.js";
import type { AuditRepository, MailflowRepository } from "../db/interfaces.js";
import type { AuditEventInput, AuditRecord } from "../audit/model.js";
import { verifyChain } from "../audit/chain.js";
import {
  buildAuditExport,
  buildOrgAuditExport,
  AUDIT_EXPORT_MAX_ROWS,
  type AuditExport,
  type OrgAuditExport,
} from "../audit/export.js";
import { assertIdentifier, RequestValidationError } from "../util/validate.js";
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
    try {
      requirePermission(actor, "mailflow.read", orgId);
    } catch (err) {
      // ADM-T250-04: read denials are audited too (denial-only — a
      // successful query stays unaudited for volume).
      if (err instanceof AuthorizationDeniedError) {
        await this.ctx.auditAppend(actor, orgId, "mailflow.query", orgId, "denied", null, { permission: "mailflow.read" }, Date.now());
      }
      throw err;
    }
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

/**
 * The audit log and its access paths.
 *
 * Self-auditing (T-259/ADM-T250-04+06): `query`, `verify`, and both exports
 * append a denial-only row when their permission check refuses — the earlier
 * "recursion" rationale was withdrawn (admin-api.md §13.4): `append` writes
 * directly and never re-enters the permission check. Successful reads still
 * stay unaudited for volume; the exports audit their successes because taking
 * a signed copy off-box is exactly the act that must leave a trace.
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
  async query(actor: Actor, filter: AuditQueryFilter): Promise<AuditRecord[]> {
    // Same org-default rule as mailflow reads (T-193/H4).
    const orgId = filter.orgId ?? actor.orgId ?? null;
    try {
      requirePermission(actor, "audit.read", orgId);
    } catch (err) {
      if (err instanceof AuthorizationDeniedError) {
        // ADM-T250-04: a refused audit READ is itself audited — appended
        // directly (append has no permission gate, so there is no recursion).
        await this.append(
          {
            actor: { subject: actor.subject, roles: actor.roles },
            orgId,
            action: "audit.query",
            resource: orgId,
            outcome: "denied",
            requestId: null,
            details: { permission: "audit.read" },
          },
          Date.now(),
        );
      }
      throw err;
    }
    const bounded = Math.min(Math.max(filter.limit, 1), 1000);
    // ADM-T250-02: the full AuditRecord — the earlier lossy projection
    // silently dropped org_id/resource/request_id and the hash-chain fields
    // a reader needs to place a row in the chain.
    return this.repos.audit.range(
      filter.since ?? 0,
      filter.until ?? Number.MAX_SAFE_INTEGER,
      bounded,
      orgId,
    );
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
  async verify(
    actor: Actor,
    opts: { limit: number },
  ): Promise<{ valid: boolean; checked: number; complete: boolean; error: string | null }> {
    try {
      requirePermission(actor, "audit.read", null);
    } catch (err) {
      if (err instanceof AuthorizationDeniedError) {
        await this.append(
          {
            actor: { subject: actor.subject, roles: actor.roles },
            orgId: null,
            action: "audit.verify",
            resource: null,
            outcome: "denied",
            requestId: null,
            details: { permission: "audit.read" },
          },
          Date.now(),
        );
      }
      throw err;
    }
    // Honest attestation (T-193/H8): limit 0 (or negative) would verify an
    // empty window and report `valid: true` — attesting nothing. Refuse
    // instead of attesting; callers that want the whole chain pass a large
    // limit or none at all.
    if (!Number.isSafeInteger(opts.limit) || opts.limit < 1) {
      throw new RequestValidationError("limit", "must be an integer >= 1");
    }
    // ADM-T250-03: a bounded window used to report `valid: true` even when it
    // covered only a chain prefix — claiming "the log is intact" for rows it
    // never saw. One extra row is fetched to detect truncation; `complete`
    // says whether the checked window was the whole chain, and `valid` is
    // only a full-chain verdict when it is.
    const bounded = Math.min(opts.limit, AUDIT_EXPORT_MAX_ROWS);
    const rows = await this.repos.audit.range(0, Number.MAX_SAFE_INTEGER, bounded + 1);
    const complete = rows.length <= bounded;
    const state = verifyChain(complete ? rows : rows.slice(0, bounded));
    return { valid: state.valid && complete, checked: state.checked, complete, error: state.error };
  }

  /**
   * T-179/T-259: signed NDJSON export of the FULL audit chain. §13 ratifies
   * this route as `system-admin`-only — `audit.export` alone is not enough:
   * org_admin holds it org-scoped, so a null-target `requirePermission` would
   * still pass. The platform role membership is the gate.
   *
   * Denials are audited (ADM-T250-06): a refused export appends an
   * `audit.export` denial row, and if that append fails the request returns
   * 500 with no body — an unaudited export is never delivered.
   *
   * There is deliberately no caller-supplied window. A truncated export would
   * still report `chain_state.valid: true` (a prefix of a valid chain is
   * itself valid), so a paged export would be indistinguishable from a
   * complete one. The export is all-or-nothing; the cap below is a memory
   * safety valve that REFUSES rather than truncating.
   */
  async export(actor: Actor, opts: { now: number; key: string | null }): Promise<AuditExport> {
    if (!(actor.roles.includes("system-admin") && hasPermission(actor, "audit.export", null))) {
      await this.append(
        {
          actor: { subject: actor.subject, roles: actor.roles },
          orgId: null,
          action: "audit.export",
          resource: null,
          outcome: "denied",
          requestId: null,
          details: { permission: "audit.export", scope: "global" },
        },
        Date.now(),
      );
      throw new AuthorizationDeniedError(actor.subject, "audit.export", null);
    }
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
    // was just before its own record.
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

  /**
   * T-259/ADM-T250-07: `GET /orgs/{orgId}/audit/export` — the org-scoped
   * artifact ratified in §13. `audit.export` is checked on the PATH org, so
   * only an actor bound to that org passes (org_admin own-org; a null-org
   * system-admin is denied — its global route is the whole-chain surface).
   *
   * The artifact is an explicitly scoped slice (`kiwi.audit-export-org/1`,
   * `scope_state` trailer, `chain_claim: "none"`) — it can never masquerade
   * as the whole chain. Self-audit row carries `org_id = oid` (§13.4),
   * written after the snapshot; a failed append returns 500 with no body.
   */
  async exportOrg(actor: Actor, orgId: string, opts: { now: number; key: string | null }): Promise<OrgAuditExport> {
    const oid = assertIdentifier(orgId, "orgId");
    try {
      requirePermission(actor, "audit.export", oid);
    } catch (err) {
      if (err instanceof AuthorizationDeniedError) {
        await this.append(
          {
            actor: { subject: actor.subject, roles: actor.roles },
            orgId: oid,
            action: "audit.export",
            resource: oid,
            outcome: "denied",
            requestId: null,
            details: { permission: "audit.export", scope: "org" },
          },
          Date.now(),
        );
      }
      throw err;
    }
    const rows = await this.repos.audit.range(0, Number.MAX_SAFE_INTEGER, AUDIT_EXPORT_MAX_ROWS + 1, oid);
    if (rows.length > AUDIT_EXPORT_MAX_ROWS) {
      throw new RequestValidationError(
        "audit",
        `org-scoped export is capped at ${AUDIT_EXPORT_MAX_ROWS} rows and this org's slice is longer; ` +
          "archive and prune the log before exporting",
      );
    }
    const result = buildOrgAuditExport(rows, oid, { now: opts.now, key: opts.key });
    await this.append(
      {
        actor: { subject: actor.subject, roles: actor.roles },
        orgId: oid,
        action: "audit.export",
        resource: oid,
        outcome: "allowed",
        requestId: null,
        details: {
          rows: result.rows,
          signed: result.signature.signed,
          key_id: result.signature.key_id,
          scope: "org",
        },
      },
      Date.now(),
    );
    return result;
  }
}
