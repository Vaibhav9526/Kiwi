/**
 * Signed NDJSON audit export (T-179).
 *
 * An audit export exists to be checked by someone who does not trust this
 * service, so the format is built around that: every row carries the hash-chain
 * fields needed to recompute the chain independently, the trailer states
 * whether the chain actually verified, and the signature covers both the rows
 * and that claim. A tampered or truncated export therefore cannot be passed off
 * as a good one — the reader recomputes line by line.
 *
 * Line layout (NDJSON, one JSON object per line, `\n`-terminated):
 *
 *   1              header      version, exported_at, row count, seq window
 *   2 .. rows+1    record      one AuditRecord per line, seq ascending
 *   rows+2         chain_state the verifyChain() verdict for exactly those rows
 *   rows+3         signature   HMAC-SHA256 over lines 1..rows+2
 *
 * The signature deliberately covers the header and the chain_state line, not
 * just the records: otherwise the "chain valid" claim and the export timestamp
 * would be editable in transit without invalidating the signature.
 *
 * Scope note: the export is always the FULL chain, never an org-filtered slice.
 * A filtered subset cannot support a chain-state claim — the chain only
 * verifies over a contiguous run of every row — so offering one would mean
 * either lying in the trailer or omitting it. Org-scoped reads live at
 * `GET /api/v1/audit?org=`, which makes no integrity claim. See
 * docs/contracts/admin-api.md §13.
 *
 * No ambient state: `now` and the key are caller-supplied, so the same records
 * with the same inputs produce byte-identical output.
 */
import { createHash, createHmac } from "node:crypto";
import type { AuditRecord } from "./model.js";
import { verifyChain, type ChainState } from "./chain.js";

/** Wire format identifier; changes if the line layout ever changes. */
export const AUDIT_EXPORT_VERSION = "kiwi.audit-export/1";

/**
 * Hard cap on exported rows. The export is the full chain by construction, so
 * a chain longer than this is refused rather than silently truncated — a
 * partial export that still claimed `chain_state.valid` would be a lie.
 */
export const AUDIT_EXPORT_MAX_ROWS = 10000;

export const AUDIT_EXPORT_CONTENT_TYPE = "application/x-ndjson";

export interface AuditExportHeader {
  type: "header";
  version: string;
  exported_at: number;
  rows: number;
  first_seq: number | null;
  last_seq: number | null;
}

export interface AuditExportChainState {
  type: "chain_state";
  valid: boolean;
  error: string | null;
  checked: number;
  head_hash: string;
  first_seq: number | null;
  last_seq: number | null;
}

export interface AuditExportSignature {
  type: "signature";
  alg: "hmac-sha256" | "none";
  signed: boolean;
  /** Fingerprint of the signing key (never the key). Null when unsigned. */
  key_id: string | null;
  signature: string | null;
  /** Highest 1-based line number covered; null when unsigned. */
  covers_through: number | null;
}

export interface AuditExport {
  ndjson: string;
  header: AuditExportHeader;
  chainState: AuditExportChainState;
  signature: AuditExportSignature;
  rows: number;
}

/**
 * Stable, non-reversible fingerprint of the signing key, published in the
 * export so a verifier can tell WHICH key signed without the key itself
 * appearing anywhere. Truncated to 16 hex chars — enough to identify a key,
 * not enough to be a useful oracle.
 */
export function auditExportKeyId(key: string): string {
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}

export interface BuildAuditExportOptions {
  /** Export timestamp, supplied by the caller (no ambient clock). */
  now: number;
  /**
   * HMAC key, or null/empty for an unsigned export. An unsigned export is
   * reported honestly (`signed: false`, `signature: null`) rather than emitting
   * a placeholder that a reader might mistake for a real signature.
   */
  key?: string | null;
}

/**
 * Build the signed NDJSON export for a window of audit records.
 *
 * The caller is responsible for passing the full chain in seq order (see
 * AuditService.export); this function reports what it was given and does not
 * fetch anything.
 */
export function buildAuditExport(
  records: readonly AuditRecord[],
  opts: BuildAuditExportOptions,
): AuditExport {
  const chain: ChainState = verifyChain(records);
  const header: AuditExportHeader = {
    type: "header",
    version: AUDIT_EXPORT_VERSION,
    exported_at: opts.now,
    rows: records.length,
    first_seq: chain.firstSeq,
    last_seq: chain.lastSeq,
  };
  const chainState: AuditExportChainState = {
    type: "chain_state",
    valid: chain.valid,
    error: chain.error,
    checked: chain.checked,
    head_hash: chain.headHash,
    first_seq: chain.firstSeq,
    last_seq: chain.lastSeq,
  };

  // Everything from the header through the chain-state line is signed as-is.
  const signedLines = [
    JSON.stringify(header),
    ...records.map((r) => JSON.stringify(r)),
    JSON.stringify(chainState),
  ];
  const signedBody = signedLines.join("\n");

  const key = (opts.key ?? "").trim();
  const signature: AuditExportSignature = key
    ? {
        type: "signature",
        alg: "hmac-sha256",
        signed: true,
        key_id: auditExportKeyId(key),
        signature: createHmac("sha256", key).update(signedBody).digest("hex"),
        covers_through: signedLines.length,
      }
    : {
        type: "signature",
        alg: "none",
        signed: false,
        key_id: null,
        signature: null,
        covers_through: null,
      };

  return {
    ndjson: `${signedBody}\n${JSON.stringify(signature)}\n`,
    header,
    chainState,
    signature,
    rows: records.length,
  };
}
