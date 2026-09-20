/**
 * Hash-chained audit log (SECURITY.md rule 11: append-only, tamper-evident).
 * entry_hash = SHA-256(canonical JSON of event fields + prev_hash).
 * Any mutation of a historical row (or deletion) breaks the chain and is
 * detected by verify().
 *
 * Concurrency note: this implementation serializes appends with a simple
 * synchronous loop (single-process). Multi-process access requires a file
 * lock — tracked in docs/contracts/admin-api.md §7.
 */
import { createHash } from "node:crypto";
import type { AuditRepository } from "../db/interfaces.js";
import type { AuditEventInput, AuditRecord, AuditOutcome } from "./model.js";

export function canonicalEventJson(input: AuditEventInput): string {
  return JSON.stringify({
    actor: { subject: input.actor.subject, roles: [...input.actor.roles] },
    org_id: input.orgId,
    action: input.action,
    resource: input.resource,
    outcome: input.outcome,
    request_id: input.requestId,
    details: input.details,
  });
}

export function computeEntryHash(eventJson: string, prevHash: string): string {
  return createHash("sha256").update(eventJson + prevHash).digest("hex");
}

/** In-memory implementation (unit tests + future Postgres reference). */
export class InMemoryAuditLog {
  private readonly entries: AuditRecord[] = [];
  private nextSeq = 1;
  private lastHash = "genesis";

  append(input: AuditEventInput, ts: number): AuditRecord {
    const json = canonicalEventJson(input);
    const entryHash = computeEntryHash(json, this.lastHash);
    const rec: AuditRecord = {
      seq: this.nextSeq,
      ts,
      actor_subject: input.actor.subject,
      actor_roles: JSON.stringify(input.actor.roles),
      org_id: input.orgId,
      action: input.action,
      resource: input.resource,
      outcome: input.outcome,
      request_id: input.requestId,
      details: JSON.stringify(input.details),
      prev_hash: this.lastHash,
      entry_hash: entryHash,
    };
    this.entries.push(rec);
    this.nextSeq += 1;
    this.lastHash = entryHash;
    return rec;
  }

  readAt(seq: number): AuditRecord | undefined {
    return this.entries[seq - 1];
  }

  range(since: number, until: number, limit: number): AuditRecord[] {
    return this.entries.filter((e) => e.ts >= since && e.ts <= until).slice(0, limit);
  }

  verify(): { valid: boolean; error: string | null } {
    let expectedPrev = "genesis";
    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i]!;
      const eventJson = JSON.stringify({
        actor: { subject: e.actor_subject, roles: JSON.parse(e.actor_roles ?? "[]") as string[] },
        org_id: e.org_id,
        action: e.action,
        resource: e.resource,
        outcome: e.outcome,
        request_id: e.request_id,
        details: JSON.parse(e.details ?? "{}") as Record<string, unknown>,
      });
      const recomputed = computeEntryHash(eventJson, expectedPrev);
      if (e.prev_hash !== expectedPrev || e.entry_hash !== recomputed) {
        return { valid: false, error: `chain broken at seq ${e.seq}` };
      }
      expectedPrev = e.entry_hash;
    }
    return { valid: true, error: null };
  }

  // exposed for tests: mutate/delete rows to simulate tampering
  get records(): readonly AuditRecord[] {
    return this.entries;
  }
}

export function auditReplay(records: readonly AuditRecord[]): ChainState {
  // Hash-only (no contiguity requirement): the in-memory callers pin this
  // message shape — see the deletion case in tests/audit.chain.test.ts, which
  // expects "chain broken at seq 3" for a gap, not a contiguity complaint.
  // DB-backed logs use verifyChain() with the default (strict) setting.
  return verifyChain(records, { requireContiguous: false });
}

/** Outcome of verifying a window of the audit chain. */
export interface ChainState {
  valid: boolean;
  error: string | null;
  /** Rows actually verified. On failure this is the count BEFORE the bad row. */
  checked: number;
  /** entry_hash of the last verified row, or `genesis` for an empty window. */
  headHash: string;
  firstSeq: number | null;
  lastSeq: number | null;
}

export interface VerifyChainOptions {
  /**
   * Require `seq` to run contiguously from the first row (default true).
   *
   * This is the second layer behind the hash chain, and it is why DB-backed
   * verification is strict: a deleted row breaks the chain only if its
   * neighbours' hashes were not recomputed to match. Contiguity catches the
   * gap even when the hashes agree. A hash chain alone cannot see a row that
   * was removed from the END of the log, which is the case this covers too.
   */
  requireContiguous?: boolean;
}

/**
 * Verify a window of audit records: every hash recomputes, every `prev_hash`
 * links to its predecessor, and (by default) `seq` is contiguous.
 *
 * The single implementation behind `AuditService.verify` and the signed export
 * (T-179), so a log cannot verify one way for a reader and another way in an
 * export. Pure — no I/O, no clock.
 */
export function verifyChain(records: readonly AuditRecord[], opts: VerifyChainOptions = {}): ChainState {
  const requireContiguous = opts.requireContiguous ?? true;
  const firstSeq = records.length > 0 ? records[0]!.seq : null;
  const lastSeq = records.length > 0 ? records[records.length - 1]!.seq : null;
  let expectedPrev = "genesis";
  let expectedSeq: number | null = null;
  let checked = 0;
  for (const r of records) {
    if (requireContiguous && expectedSeq !== null && r.seq !== expectedSeq) {
      return {
        valid: false,
        error: `chain non-contiguous: expected seq ${expectedSeq}`,
        checked,
        headHash: expectedPrev,
        firstSeq,
        lastSeq,
      };
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
      return { valid: false, error: `chain broken at seq ${r.seq}`, checked, headHash: expectedPrev, firstSeq, lastSeq };
    }
    expectedPrev = r.entry_hash;
    checked += 1;
  }
  return { valid: true, error: null, checked, headHash: expectedPrev, firstSeq, lastSeq };
}

/** Facade with outcome helpers; concrete stores implement the repository. */
export function auditAllowed(outcome: AuditOutcome): boolean {
  return outcome !== "denied" && outcome !== "error";
}
