/**
 * Bounded validation helpers (T-136). Mirrors kiwi-admin's
 * `src/util/validate.ts` philosophy: bounded, dependency-free, total
 * functions; assertX throws, isX predicates never throw.
 */
export class RequestValidationError extends Error {
  constructor(
    public readonly field: string,
    reason: string,
  ) {
    super(`invalid ${field}: ${reason}`);
    this.name = "RequestValidationError";
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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

export function assertBoundedString(value: unknown, field: string, min: number, max: number): string {
  if (typeof value !== "string") throw new RequestValidationError(field, "expected string");
  if (value.length < min || value.length > max) {
    throw new RequestValidationError(field, `length must be ${min}..${max}`);
  }
  return value;
}

/** RFC 4648 base64 (A–Z a–z 0–9 + / =) only — no padding-optional laxness. */
export function isBase64(value: string): boolean {
  return /^[A-Za-z0-9+/]*={0,2}$/.test(value) && value.length % 4 === 0;
}

export function assertBase64(value: unknown, field: string, maxDecodedBytes: number): string {
  const s = assertBoundedString(value, field, 1, Math.ceil(maxDecodedBytes / 3) * 4 + 4);
  if (!isBase64(s)) throw new RequestValidationError(field, "expected base64");
  return s;
}
