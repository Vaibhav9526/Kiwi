import { describe, expect, it } from "vitest";
import { PUBLIC_INBOX_NOTICE } from "./kiwi";
import {
  decodeDeliverabilityBeginView,
  decodeDeliverabilityReportView,
  decodeDeliverabilitySendView,
  decodeDeliverabilityStatusView,
  decodeIntegrationAuthGate,
  decodeTempDiscardView,
  decodeTempExtendView,
  decodeTempMailboxView,
  decodeTempMessageView,
  decodeTempPollView,
} from "./integrations";

const tempSummary = {
  mailId: "mail-1",
  from: "sender@example.test",
  subject: "Hello",
  excerpt: "Body",
  date: "2026-09-25",
  read: false,
};

const tempMailbox = {
  address: "throwaway@example.test",
  addressCreatedUnix: 1_700_000_000,
  publicInboxNotice: PUBLIC_INBOX_NOTICE,
};

const tempPoll = {
  messages: [tempSummary],
  totalNew: 1,
  address: tempMailbox.address,
  publicInboxNotice: PUBLIC_INBOX_NOTICE,
};

const tempMessage = {
  mailId: tempSummary.mailId,
  from: tempSummary.from,
  subject: tempSummary.subject,
  date: tempSummary.date,
  html: "<p>Hello</p>",
  remoteImagesStripped: 0,
  publicInboxNotice: PUBLIC_INBOX_NOTICE,
};

const tempDiscard = {
  discarded: true,
  remoteForgotten: false,
  publicInboxNotice: PUBLIC_INBOX_NOTICE,
};

const tempExtend = {
  extended: true,
  expired: false,
  publicInboxNotice: PUBLIC_INBOX_NOTICE,
};

const begin = {
  testId: "test-1",
  address: "sink@example.test",
  consentToken: "consent-1",
  consentNotice: "Third-party delivery consent",
};

const send = {
  testId: begin.testId,
  queueId: "queue-1",
  notBeforeUnix: 1_700_000_001,
};

const status = {
  testId: begin.testId,
  analysisStatus: "analyzing",
  checksDone: 1,
  checksTotal: 2,
  ready: false,
  sent: true,
};

const report = {
  testId: begin.testId,
  scoreOursMilli: 87_000,
  scoreCompatMilli: 9_100,
  complete: true,
  reportUrl: "https://reports.example.test/result",
  subscores: { auth: 100_000 },
  tallies: { auth: { pass: 1, warn: 0, fail: 0, skip: 0, other: 0 } },
  checks: [
    {
      id: "spf",
      category: "auth",
      categoryRaw: "auth",
      status: "pass",
      title: "SPF",
      summary: "passes",
      citations: [{ kind: "standards", title: "RFC", url: "https://www.rfc-editor.org/rfc/rfc7208" }],
    },
  ],
  authFailureIds: [],
  authGate: "pass",
};

describe("integration response decoders", () => {
  it("decodes all five temp-mail success responses", () => {
    expect(decodeTempMailboxView(tempMailbox)).toEqual(tempMailbox);
    expect(decodeTempPollView(tempPoll)).toEqual(tempPoll);
    expect(decodeTempMessageView(tempMessage)).toEqual(tempMessage);
    expect(decodeTempDiscardView(tempDiscard)).toEqual(tempDiscard);
    expect(decodeTempExtendView(tempExtend)).toEqual(tempExtend);
  });

  it("decodes all four deliverability success responses", () => {
    expect(decodeDeliverabilityBeginView(begin)).toEqual(begin);
    expect(decodeDeliverabilitySendView(send)).toEqual(send);
    expect(decodeDeliverabilityStatusView(status)).toEqual(status);
    expect(decodeDeliverabilityReportView(report)).toEqual(report);
  });

  it("rejects malformed response roots and fields", () => {
    expect(decodeTempMailboxView(null)).toBeNull();
    expect(decodeTempPollView({ ...tempPoll, messages: {} })).toBeNull();
    expect(decodeTempMessageView({ ...tempMessage, remoteImagesStripped: -1 })).toBeNull();
    expect(decodeTempDiscardView({ ...tempDiscard, discarded: "yes" })).toBeNull();
    expect(decodeTempExtendView({ ...tempExtend, publicInboxNotice: "changed" })).toBeNull();
    expect(decodeDeliverabilityBeginView({ ...begin, consentToken: "" })).toBeNull();
    expect(decodeDeliverabilitySendView({ ...send, queueId: 1 })).toBeNull();
    expect(decodeDeliverabilityStatusView({ ...status, checksDone: 3 })).toBeNull();
    expect(decodeDeliverabilityReportView({ ...report, checks: {} })).toBeNull();
  });

  it("requires the mandated temp-mail notice on every response", () => {
    expect(decodeTempMailboxView({ ...tempMailbox, publicInboxNotice: undefined })).toBeNull();
    expect(decodeTempPollView({ ...tempPoll, publicInboxNotice: undefined })).toBeNull();
    expect(decodeTempMessageView({ ...tempMessage, publicInboxNotice: undefined })).toBeNull();
    expect(decodeTempDiscardView({ ...tempDiscard, publicInboxNotice: undefined })).toBeNull();
    expect(decodeTempExtendView({ ...tempExtend, publicInboxNotice: undefined })).toBeNull();
  });

  it("fails closed when the report auth gate is missing or unknown", () => {
    expect(decodeIntegrationAuthGate({ authGate: "pass" })).toBe("pass");
    expect(decodeIntegrationAuthGate({ authGate: "clear" })).toBe("pass");
    expect(decodeIntegrationAuthGate({ authGate: { state: "blocked" } })).toBe("fail");
    expect(decodeIntegrationAuthGate({ authGate: "blocked" })).toBe("fail");
    expect(decodeIntegrationAuthGate({})).toBeNull();
    expect(decodeDeliverabilityReportView({ ...report, authGate: undefined })).toBeNull();
    expect(decodeDeliverabilityReportView({ ...report, authGate: "mystery" })).toEqual({
      ...report,
      authGate: "unknown",
    });
  });

  it("accepts bounded HTTPS report and citation URLs only", () => {
    expect(decodeDeliverabilityReportView({ ...report, reportUrl: "https://reports.example.test/a" })).not.toBeNull();
    expect(decodeDeliverabilityReportView({ ...report, reportUrl: "http://reports.example.test/a" })).toBeNull();
    expect(decodeDeliverabilityReportView({ ...report, reportUrl: "javascript:alert(1)" })).toBeNull();
    expect(
      decodeDeliverabilityReportView({
        ...report,
        checks: [{ ...report.checks[0], citations: [{ ...report.checks[0].citations[0], url: "data:text/html,x" }] }],
      }),
    ).toBeNull();
  });

  it("validates the optional retry hint", () => {
    expect(decodeDeliverabilityStatusView({ ...status, retryAfterMs: 1_234 })).toEqual({ ...status, retryAfterMs: 1_234 });
    expect(decodeDeliverabilityStatusView({ ...status, retryAfterMs: -1 })).toBeNull();
    expect(decodeDeliverabilityStatusView({ ...status, retryAfterMs: 3_600_001 })).toBeNull();
  });
});
