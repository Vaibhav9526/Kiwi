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

export function auditReplay(records: readonly AuditRecord[]): { valid: boolean; error: string | null } {
  let expectedPrev = "genesis";
  for (const e of records) {
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

/** Facade with outcome helpers; concrete stores implement the repository. */
export function auditAllowed(outcome: AuditOutcome): boolean {
  return outcome !== "denied" && outcome !== "error";
}
