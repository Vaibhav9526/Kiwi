import { PUBLIC_INBOX_NOTICE } from "./kiwi";
import type {
  DeliverabilityBeginView,
  DeliverabilityCategoryTally,
  DeliverabilityCheckView,
  DeliverabilityCitationView,
  DeliverabilityReportView,
  DeliverabilitySendView,
  DeliverabilityStatusView,
  TempDiscardView,
  TempExtendView,
  TempMailboxView,
  TempMessageSummaryView,
  TempMessageView,
  TempPollView,
} from "./kiwi";

type JsonRecord = Record<string, unknown>;
export type DeliverabilityAuthGate = "pass" | "fail" | "unknown";

const has = (record: JsonRecord, key: string): boolean => Object.prototype.hasOwnProperty.call(record, key);

function fail(): never {
  throw new Error("invalid integration response");
}

function record(raw: unknown): JsonRecord {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) fail();
  return raw as JsonRecord;
}

function requiredString(source: JsonRecord, key: string, allowEmpty = false): string {
  const value = source[key];
  if (typeof value !== "string" || value.length > 8 * 1024 * 1024 || (!allowEmpty && value.length === 0)) fail();
  return value;
}

function optionalString(source: JsonRecord, key: string, allowEmpty = false): string | undefined {
  if (!has(source, key) || source[key] === undefined) return undefined;
  const value = source[key];
  if (typeof value !== "string" || value.length > 8 * 1024 * 1024 || (!allowEmpty && value.length === 0)) fail();
  return value;
}

function requiredBoolean(source: JsonRecord, key: string): boolean {
  const value = source[key];
  if (typeof value !== "boolean") fail();
  return value;
}

function integer(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) fail();
  return value;
}

function optionalInteger(source: JsonRecord, key: string, min = 0, max = Number.MAX_SAFE_INTEGER): number | undefined {
  if (!has(source, key) || source[key] === undefined) return undefined;
  return integer(source[key], min, max);
}

function array(source: JsonRecord, key: string): unknown[] {
  const value = source[key];
  if (!Array.isArray(value)) fail();
  return value;
}

function stringList(source: JsonRecord, key: string): string[] {
  return array(source, key).map((value) => {
    if (typeof value !== "string" || value.length === 0) fail();
    return value;
  });
}

function numberMap(source: JsonRecord, key: string): Record<string, number> {
  const value = source[key];
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail();
  const output: Record<string, number> = {};
  for (const [entryKey, entryValue] of Object.entries(value as JsonRecord)) {
    output[entryKey] = integer(entryValue);
  }
  return output;
}

function httpsUrl(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) fail();
  if (!value.split("").every((character) => character.charCodeAt(0) >= 0x21 && character.charCodeAt(0) <= 0x7e)) fail();
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password || parsed.hash) fail();
  } catch {
    fail();
  }
  return value;
}

function optionalHttpsUrl(source: JsonRecord, key: string): string | undefined {
  if (!has(source, key) || source[key] === undefined) return undefined;
  return httpsUrl(source[key]);
}

function publicNotice(source: JsonRecord): string {
  const value = requiredString(source, "publicInboxNotice");
  if (value !== PUBLIC_INBOX_NOTICE) fail();
  return value;
}

function optionalRetryAfterMs(source: JsonRecord): number | undefined {
  if (!has(source, "retryAfterMs") && !has(source, "retry_after_ms")) return undefined;
  const value = has(source, "retryAfterMs") ? source["retryAfterMs"] : source["retry_after_ms"];
  return integer(value, 0, 60 * 60 * 1000);
}

function decode<T>(decoder: () => T): T | null {
  try {
    return decoder();
  } catch {
    return null;
  }
}

export function decodeIntegrationAuthGate(raw: unknown): DeliverabilityAuthGate | null {
  return decode(() => {
    const source = record(raw);
    if (!has(source, "authGate") || source["authGate"] === undefined || source["authGate"] === null) fail();
    const value = source["authGate"];
    if (value === true || value === "pass" || value === "clear" || value === "trusted" || value === "ok") return "pass";
    if (value === false || value === "fail" || value === "failed" || value === "blocked" || value === "denied") return "fail";
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      const gate = value as JsonRecord;
      if (gate["allowed"] === true || gate["passed"] === true || gate["trusted"] === true) return "pass";
      if (gate["allowed"] === false || gate["passed"] === false || gate["trusted"] === false) return "fail";
      const status = gate["state"] ?? gate["status"] ?? gate["outcome"] ?? gate["result"] ?? gate["kind"];
      if (status === "pass" || status === "clear" || status === "trusted" || status === "ok") return "pass";
      if (status === "fail" || status === "failed" || status === "blocked" || status === "denied") return "fail";
    }
    return "unknown";
  });
}

function decodeMessageSummary(raw: unknown): TempMessageSummaryView {
  const source = record(raw);
  return {
    mailId: requiredString(source, "mailId"),
    from: requiredString(source, "from", true),
    subject: requiredString(source, "subject", true),
    excerpt: requiredString(source, "excerpt", true),
    timestampUnix: optionalInteger(source, "timestampUnix"),
    date: requiredString(source, "date", true),
    read: requiredBoolean(source, "read"),
  };
}

export function decodeTempMailboxView(raw: unknown): TempMailboxView | null {
  return decode(() => {
    const source = record(raw);
    return {
      address: requiredString(source, "address"),
      addressCreatedUnix: optionalInteger(source, "addressCreatedUnix"),
      publicInboxNotice: publicNotice(source),
    };
  });
}

export function decodeTempPollView(raw: unknown): TempPollView | null {
  return decode(() => {
    const source = record(raw);
    return {
      messages: array(source, "messages").map(decodeMessageSummary),
      totalNew: integer(source["totalNew"]),
      address: optionalString(source, "address"),
      publicInboxNotice: publicNotice(source),
    };
  });
}

export function decodeTempMessageView(raw: unknown): TempMessageView | null {
  return decode(() => {
    const source = record(raw);
    return {
      mailId: requiredString(source, "mailId"),
      from: requiredString(source, "from", true),
      subject: requiredString(source, "subject", true),
      date: requiredString(source, "date", true),
      contentType: optionalString(source, "contentType"),
      html: optionalString(source, "html", true),
      text: optionalString(source, "text", true),
      remoteImagesStripped: integer(source["remoteImagesStripped"]),
      publicInboxNotice: publicNotice(source),
    };
  });
}

export function decodeTempDiscardView(raw: unknown): TempDiscardView | null {
  return decode(() => {
    const source = record(raw);
    return {
      discarded: requiredBoolean(source, "discarded"),
      remoteForgotten: requiredBoolean(source, "remoteForgotten"),
      publicInboxNotice: publicNotice(source),
    };
  });
}

export function decodeTempExtendView(raw: unknown): TempExtendView | null {
  return decode(() => {
    const source = record(raw);
    return {
      extended: requiredBoolean(source, "extended"),
      expired: requiredBoolean(source, "expired"),
      addressCreatedUnix: optionalInteger(source, "addressCreatedUnix"),
      publicInboxNotice: publicNotice(source),
    };
  });
}

export function decodeDeliverabilityBeginView(raw: unknown): DeliverabilityBeginView | null {
  return decode(() => {
    const source = record(raw);
    return {
      testId: requiredString(source, "testId"),
      address: requiredString(source, "address"),
      expiresAtUnix: optionalInteger(source, "expiresAtUnix"),
      expiresAtRaw: optionalString(source, "expiresAtRaw"),
      consentToken: requiredString(source, "consentToken"),
      consentNotice: requiredString(source, "consentNotice"),
    };
  });
}

export function decodeDeliverabilitySendView(raw: unknown): DeliverabilitySendView | null {
  return decode(() => {
    const source = record(raw);
    return {
      testId: requiredString(source, "testId"),
      queueId: requiredString(source, "queueId"),
      notBeforeUnix: integer(source["notBeforeUnix"], Number.MIN_SAFE_INTEGER),
      consentConsumed: requiredBoolean(source, "consentConsumed"),
      enqueued: requiredBoolean(source, "enqueued"),
      singleAttempt: requiredBoolean(source, "singleAttempt"),
    };
  });
}

export function decodeDeliverabilityStatusView(raw: unknown): DeliverabilityStatusView | null {
  return decode(() => {
    const source = record(raw);
    const checksDone = integer(source["checksDone"]);
    const checksTotal = integer(source["checksTotal"]);
    if (checksDone > checksTotal) fail();
    return {
      testId: requiredString(source, "testId"),
      analysisStatus: requiredString(source, "analysisStatus"),
      checksDone,
      checksTotal,
      ready: requiredBoolean(source, "ready"),
      sent: requiredBoolean(source, "sent"),
      consentConsumed: requiredBoolean(source, "consentConsumed"),
      retryAfterMs: optionalRetryAfterMs(source),
    };
  });
}

function decodeCitation(raw: unknown): DeliverabilityCitationView {
  const source = record(raw);
  return {
    kind: requiredString(source, "kind"),
    title: requiredString(source, "title"),
    url: httpsUrl(source["url"]),
  };
}

function decodeTally(raw: unknown): DeliverabilityCategoryTally {
  const source = record(raw);
  return {
    pass: integer(source["pass"]),
    warn: integer(source["warn"]),
    fail: integer(source["fail"]),
    skip: integer(source["skip"]),
    other: integer(source["other"]),
  };
}

function decodeCheck(raw: unknown): DeliverabilityCheckView {
  const source = record(raw);
  return {
    id: requiredString(source, "id"),
    category: requiredString(source, "category"),
    categoryRaw: requiredString(source, "categoryRaw", true),
    status: requiredString(source, "status"),
    title: requiredString(source, "title", true),
    summary: requiredString(source, "summary", true),
    citations: array(source, "citations").map(decodeCitation),
  };
}

export function decodeDeliverabilityReportView(raw: unknown): DeliverabilityReportView | null {
  return decode(() => {
    const source = record(raw);
    const authGate = decodeIntegrationAuthGate(source);
    if (authGate === null) fail();
    return {
      testId: requiredString(source, "testId"),
      scoreOursMilli: optionalInteger(source, "scoreOursMilli", 0, 100_000),
      scoreCompatMilli: optionalInteger(source, "scoreCompatMilli", 0, 10_000),
      complete: requiredBoolean(source, "complete"),
      reportUrl: optionalHttpsUrl(source, "reportUrl"),
      subscores: numberMap(source, "subscores"),
      tallies: Object.fromEntries(
        Object.entries(record(source["tallies"])).map(([key, value]) => [key, decodeTally(value)]),
      ),
      checks: array(source, "checks").map(decodeCheck),
      authFailureIds: stringList(source, "authFailureIds"),
      authGate,
      checksTruncated: requiredBoolean(source, "checksTruncated"),
      evidenceComplete: requiredBoolean(source, "evidenceComplete"),
    };
  });
}
