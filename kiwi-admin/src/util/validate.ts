/**
 * Small synchronous validation helpers. Every external payload crossing an
 * API or ingest boundary must pass through these before use (SECURITY.md
 * rule 9: all externally supplied data is untrusted).
 *
 * Philosophy: bounded, dependency-free, total functions. `assertX` throws
 * RequestValidationError; `isX` predicates never throw.
 */
export class RequestValidationError extends Error {
  constructor(field: string, reason: string) {
    super(`invalid ${field}: ${reason}`);
    this.name = "RequestValidationError";
  }
}

const MAX_STRING = 4096;
const MAX_ID = 256;

export function assertNonEmptyString(value: unknown, field: string, maxLength: number = MAX_STRING): string {
  if (typeof value !== "string") throw new RequestValidationError(field, "expected string");
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new RequestValidationError(field, "must not be empty");
  if (trimmed.length > maxLength) throw new RequestValidationError(field, `exceeds ${maxLength} chars`);
  return trimmed;
}

export function assertIdentifier(value: unknown, field: string): string {
  const s = assertNonEmptyString(value, field, MAX_ID);
  if (!/^[\w@.:-]+$/.test(s)) throw new RequestValidationError(field, "unexpected characters");
  return s;
}

export function assertOptionalNonEmptyString(
  value: unknown,
  field: string,
  maxLength: number = MAX_STRING,
): string | undefined {
  if (value === undefined || value === null) return undefined;
  return assertNonEmptyString(value, field, maxLength);
}

export function isFiniteInt(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

export function assertInt(value: unknown, field: string): number {
  if (!isFiniteInt(value)) throw new RequestValidationError(field, "expected integer");
  return value;
}

export function assertIntInRange(value: unknown, field: string, min: number, max: number): number {
  const n = assertInt(value, field);
  if (n < min || n > max) throw new RequestValidationError(field, `must be between ${min} and ${max}`);
  return n;
}

export function assertBool(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw new RequestValidationError(field, "expected boolean");
  return value;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
